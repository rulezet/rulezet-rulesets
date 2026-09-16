rule TTP_XOR_QUAD_CurrentVersionRun_f702 {
  strings:
    $key_f702 = { a4 6d [2] 80 63 [2] ab 4f [2] 85 6d [2] 91 76 [2] 9e 6c [2] 80 71 [2] 82 70 [2] 99 76 [2] 85 71 [2] 99 5e }

  condition:
    any of them
}