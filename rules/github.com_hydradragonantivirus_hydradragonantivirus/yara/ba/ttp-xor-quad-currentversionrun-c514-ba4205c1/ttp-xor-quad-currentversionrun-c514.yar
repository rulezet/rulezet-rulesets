rule TTP_XOR_QUAD_CurrentVersionRun_c514 {
  strings:
    $key_c514 = { 96 7b [2] b2 75 [2] 99 59 [2] b7 7b [2] a3 60 [2] ac 7a [2] b2 67 [2] b0 66 [2] ab 60 [2] b7 67 [2] ab 48 }

  condition:
    any of them
}