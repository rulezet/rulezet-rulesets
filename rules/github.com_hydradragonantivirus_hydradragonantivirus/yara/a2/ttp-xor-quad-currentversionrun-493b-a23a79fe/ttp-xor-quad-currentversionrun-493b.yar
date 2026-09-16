rule TTP_XOR_QUAD_CurrentVersionRun_493b {
  strings:
    $key_493b = { 1a 54 [2] 3e 5a [2] 15 76 [2] 3b 54 [2] 2f 4f [2] 20 55 [2] 3e 48 [2] 3c 49 [2] 27 4f [2] 3b 48 [2] 27 67 }

  condition:
    any of them
}