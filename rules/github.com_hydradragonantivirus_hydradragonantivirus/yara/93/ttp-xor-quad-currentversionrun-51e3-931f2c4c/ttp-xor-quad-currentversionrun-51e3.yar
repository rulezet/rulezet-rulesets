rule TTP_XOR_QUAD_CurrentVersionRun_51e3 {
  strings:
    $key_51e3 = { 02 8c [2] 26 82 [2] 0d ae [2] 23 8c [2] 37 97 [2] 38 8d [2] 26 90 [2] 24 91 [2] 3f 97 [2] 23 90 [2] 3f bf }

  condition:
    any of them
}