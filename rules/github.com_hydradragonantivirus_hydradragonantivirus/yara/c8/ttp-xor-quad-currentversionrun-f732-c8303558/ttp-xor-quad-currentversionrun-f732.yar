rule TTP_XOR_QUAD_CurrentVersionRun_f732 {
  strings:
    $key_f732 = { a4 5d [2] 80 53 [2] ab 7f [2] 85 5d [2] 91 46 [2] 9e 5c [2] 80 41 [2] 82 40 [2] 99 46 [2] 85 41 [2] 99 6e }

  condition:
    any of them
}