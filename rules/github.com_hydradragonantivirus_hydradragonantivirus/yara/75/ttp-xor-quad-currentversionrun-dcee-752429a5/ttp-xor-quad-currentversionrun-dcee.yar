rule TTP_XOR_QUAD_CurrentVersionRun_dcee {
  strings:
    $key_dcee = { 8f 81 [2] ab 8f [2] 80 a3 [2] ae 81 [2] ba 9a [2] b5 80 [2] ab 9d [2] a9 9c [2] b2 9a [2] ae 9d [2] b2 b2 }

  condition:
    any of them
}