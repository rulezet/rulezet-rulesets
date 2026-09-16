rule TTP_XOR_QUAD_CurrentVersionRun_e9e3 {
  strings:
    $key_e9e3 = { ba 8c [2] 9e 82 [2] b5 ae [2] 9b 8c [2] 8f 97 [2] 80 8d [2] 9e 90 [2] 9c 91 [2] 87 97 [2] 9b 90 [2] 87 bf }

  condition:
    any of them
}