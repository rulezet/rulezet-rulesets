rule TTP_XOR_QUAD_CurrentVersionRun_65e3 {
  strings:
    $key_65e3 = { 36 8c [2] 12 82 [2] 39 ae [2] 17 8c [2] 03 97 [2] 0c 8d [2] 12 90 [2] 10 91 [2] 0b 97 [2] 17 90 [2] 0b bf }

  condition:
    any of them
}