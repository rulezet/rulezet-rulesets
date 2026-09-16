rule TTP_XOR_QUAD_CurrentVersionRun_c238 {
  strings:
    $key_c238 = { 91 57 [2] b5 59 [2] 9e 75 [2] b0 57 [2] a4 4c [2] ab 56 [2] b5 4b [2] b7 4a [2] ac 4c [2] b0 4b [2] ac 64 }

  condition:
    any of them
}