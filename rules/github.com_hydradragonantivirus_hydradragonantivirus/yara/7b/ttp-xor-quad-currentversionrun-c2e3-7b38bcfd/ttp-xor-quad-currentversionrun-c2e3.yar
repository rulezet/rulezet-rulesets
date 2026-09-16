rule TTP_XOR_QUAD_CurrentVersionRun_c2e3 {
  strings:
    $key_c2e3 = { 91 8c [2] b5 82 [2] 9e ae [2] b0 8c [2] a4 97 [2] ab 8d [2] b5 90 [2] b7 91 [2] ac 97 [2] b0 90 [2] ac bf }

  condition:
    any of them
}