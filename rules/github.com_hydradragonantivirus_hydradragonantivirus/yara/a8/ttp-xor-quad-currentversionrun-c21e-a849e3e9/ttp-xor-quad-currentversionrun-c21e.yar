rule TTP_XOR_QUAD_CurrentVersionRun_c21e {
  strings:
    $key_c21e = { 91 71 [2] b5 7f [2] 9e 53 [2] b0 71 [2] a4 6a [2] ab 70 [2] b5 6d [2] b7 6c [2] ac 6a [2] b0 6d [2] ac 42 }

  condition:
    any of them
}