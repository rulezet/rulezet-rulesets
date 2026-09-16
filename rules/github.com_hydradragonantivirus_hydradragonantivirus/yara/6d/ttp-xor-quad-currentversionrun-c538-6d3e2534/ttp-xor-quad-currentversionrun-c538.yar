rule TTP_XOR_QUAD_CurrentVersionRun_c538 {
  strings:
    $key_c538 = { 96 57 [2] b2 59 [2] 99 75 [2] b7 57 [2] a3 4c [2] ac 56 [2] b2 4b [2] b0 4a [2] ab 4c [2] b7 4b [2] ab 64 }

  condition:
    any of them
}