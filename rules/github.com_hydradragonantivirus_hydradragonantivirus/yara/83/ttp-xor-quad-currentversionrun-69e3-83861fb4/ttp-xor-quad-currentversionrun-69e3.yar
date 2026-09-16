rule TTP_XOR_QUAD_CurrentVersionRun_69e3 {
  strings:
    $key_69e3 = { 3a 8c [2] 1e 82 [2] 35 ae [2] 1b 8c [2] 0f 97 [2] 00 8d [2] 1e 90 [2] 1c 91 [2] 07 97 [2] 1b 90 [2] 07 bf }

  condition:
    any of them
}