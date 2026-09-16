rule SolidityUnsafeAdd {
  strings:
        $sol_mempointer_alloc = {
      60 80        60 40        52         }
    $add_ballance         = {
      54        01        92        50        50        81        90        55      }
    $require_no_overflow  = {
      01        10        15        15        15        60      }

  condition:
    $sol_mempointer_alloc at 0 and
    not $require_no_overflow in (@add_ballance - 30..@add_ballance)
}