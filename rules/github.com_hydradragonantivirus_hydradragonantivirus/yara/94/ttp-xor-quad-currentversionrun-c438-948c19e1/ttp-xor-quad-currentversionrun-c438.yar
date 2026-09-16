rule TTP_XOR_QUAD_CurrentVersionRun_c438 {
  strings:
    $key_c438 = { 97 57 [2] b3 59 [2] 98 75 [2] b6 57 [2] a2 4c [2] ad 56 [2] b3 4b [2] b1 4a [2] aa 4c [2] b6 4b [2] aa 64 }

  condition:
    any of them
}