rule TTP_XOR_QUAD_CurrentVersionRun_c218 {
  strings:
    $key_c218 = { 91 77 [2] b5 79 [2] 9e 55 [2] b0 77 [2] a4 6c [2] ab 76 [2] b5 6b [2] b7 6a [2] ac 6c [2] b0 6b [2] ac 44 }

  condition:
    any of them
}