rule TTP_XOR_QUAD_CurrentVersionRun_c202 {
  strings:
    $key_c202 = { 91 6d [2] b5 63 [2] 9e 4f [2] b0 6d [2] a4 76 [2] ab 6c [2] b5 71 [2] b7 70 [2] ac 76 [2] b0 71 [2] ac 5e }

  condition:
    any of them
}