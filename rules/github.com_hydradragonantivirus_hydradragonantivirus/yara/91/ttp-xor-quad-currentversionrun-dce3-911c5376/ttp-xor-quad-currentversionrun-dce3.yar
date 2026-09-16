rule TTP_XOR_QUAD_CurrentVersionRun_dce3 {
  strings:
    $key_dce3 = { 8f 8c [2] ab 82 [2] 80 ae [2] ae 8c [2] ba 97 [2] b5 8d [2] ab 90 [2] a9 91 [2] b2 97 [2] ae 90 [2] b2 bf }

  condition:
    any of them
}