rule TTP_XOR_QUAD_CurrentVersionRun_f722 {
  strings:
    $key_f722 = { a4 4d [2] 80 43 [2] ab 6f [2] 85 4d [2] 91 56 [2] 9e 4c [2] 80 51 [2] 82 50 [2] 99 56 [2] 85 51 [2] 99 7e }

  condition:
    any of them
}