rule TTP_XOR_QUAD_CurrentVersionRun_d01e {
  strings:
    $key_d01e = { 83 71 [2] a7 7f [2] 8c 53 [2] a2 71 [2] b6 6a [2] b9 70 [2] a7 6d [2] a5 6c [2] be 6a [2] a2 6d [2] be 42 }

  condition:
    any of them
}