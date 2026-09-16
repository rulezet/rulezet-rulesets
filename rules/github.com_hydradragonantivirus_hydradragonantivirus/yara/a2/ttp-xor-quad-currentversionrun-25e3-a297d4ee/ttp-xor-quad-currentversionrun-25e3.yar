rule TTP_XOR_QUAD_CurrentVersionRun_25e3 {
  strings:
    $key_25e3 = { 76 8c [2] 52 82 [2] 79 ae [2] 57 8c [2] 43 97 [2] 4c 8d [2] 52 90 [2] 50 91 [2] 4b 97 [2] 57 90 [2] 4b bf }

  condition:
    any of them
}