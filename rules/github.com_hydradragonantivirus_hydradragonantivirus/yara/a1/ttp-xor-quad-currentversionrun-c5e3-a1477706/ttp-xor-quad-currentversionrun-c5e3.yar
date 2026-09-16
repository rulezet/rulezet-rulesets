rule TTP_XOR_QUAD_CurrentVersionRun_c5e3 {
  strings:
    $key_c5e3 = { 96 8c [2] b2 82 [2] 99 ae [2] b7 8c [2] a3 97 [2] ac 8d [2] b2 90 [2] b0 91 [2] ab 97 [2] b7 90 [2] ab bf }

  condition:
    any of them
}