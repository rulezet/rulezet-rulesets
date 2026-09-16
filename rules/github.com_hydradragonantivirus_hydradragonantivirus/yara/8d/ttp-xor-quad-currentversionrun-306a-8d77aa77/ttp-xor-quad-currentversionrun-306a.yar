rule TTP_XOR_QUAD_CurrentVersionRun_306a {
  strings:
    $key_306a = { 63 05 [2] 47 0b [2] 6c 27 [2] 42 05 [2] 56 1e [2] 59 04 [2] 47 19 [2] 45 18 [2] 5e 1e [2] 42 19 [2] 5e 36 }

  condition:
    any of them
}