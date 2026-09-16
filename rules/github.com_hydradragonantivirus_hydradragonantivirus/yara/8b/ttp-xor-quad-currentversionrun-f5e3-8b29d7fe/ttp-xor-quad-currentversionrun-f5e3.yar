rule TTP_XOR_QUAD_CurrentVersionRun_f5e3 {
  strings:
    $key_f5e3 = { a6 8c [2] 82 82 [2] a9 ae [2] 87 8c [2] 93 97 [2] 9c 8d [2] 82 90 [2] 80 91 [2] 9b 97 [2] 87 90 [2] 9b bf }

  condition:
    any of them
}