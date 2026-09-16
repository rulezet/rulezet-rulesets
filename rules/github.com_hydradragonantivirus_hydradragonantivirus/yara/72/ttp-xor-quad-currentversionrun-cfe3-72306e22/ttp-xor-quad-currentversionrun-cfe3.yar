rule TTP_XOR_QUAD_CurrentVersionRun_cfe3 {
  strings:
    $key_cfe3 = { 9c 8c [2] b8 82 [2] 93 ae [2] bd 8c [2] a9 97 [2] a6 8d [2] b8 90 [2] ba 91 [2] a1 97 [2] bd 90 [2] a1 bf }

  condition:
    any of them
}