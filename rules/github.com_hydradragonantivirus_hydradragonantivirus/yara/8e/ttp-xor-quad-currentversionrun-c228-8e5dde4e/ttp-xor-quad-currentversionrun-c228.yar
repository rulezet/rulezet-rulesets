rule TTP_XOR_QUAD_CurrentVersionRun_c228 {
  strings:
    $key_c228 = { 91 47 [2] b5 49 [2] 9e 65 [2] b0 47 [2] a4 5c [2] ab 46 [2] b5 5b [2] b7 5a [2] ac 5c [2] b0 5b [2] ac 74 }

  condition:
    any of them
}