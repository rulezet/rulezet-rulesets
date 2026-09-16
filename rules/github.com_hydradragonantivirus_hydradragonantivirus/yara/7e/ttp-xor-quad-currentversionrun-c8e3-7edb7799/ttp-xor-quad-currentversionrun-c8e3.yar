rule TTP_XOR_QUAD_CurrentVersionRun_c8e3 {
  strings:
    $key_c8e3 = { 9b 8c [2] bf 82 [2] 94 ae [2] ba 8c [2] ae 97 [2] a1 8d [2] bf 90 [2] bd 91 [2] a6 97 [2] ba 90 [2] a6 bf }

  condition:
    any of them
}