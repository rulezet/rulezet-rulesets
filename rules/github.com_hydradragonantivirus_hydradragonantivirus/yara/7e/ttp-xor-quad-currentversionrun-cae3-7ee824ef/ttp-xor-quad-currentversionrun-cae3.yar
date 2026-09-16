rule TTP_XOR_QUAD_CurrentVersionRun_cae3 {
  strings:
    $key_cae3 = { 99 8c [2] bd 82 [2] 96 ae [2] b8 8c [2] ac 97 [2] a3 8d [2] bd 90 [2] bf 91 [2] a4 97 [2] b8 90 [2] a4 bf }

  condition:
    any of them
}