rule TTP_XOR_QUAD_CurrentVersionRun_01e3 {
  strings:
    $key_01e3 = { 52 8c [2] 76 82 [2] 5d ae [2] 73 8c [2] 67 97 [2] 68 8d [2] 76 90 [2] 74 91 [2] 6f 97 [2] 73 90 [2] 6f bf }

  condition:
    any of them
}