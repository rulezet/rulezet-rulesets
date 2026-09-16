rule TTP_XOR_QUAD_CurrentVersionRun_c52e {
  strings:
    $key_c52e = { 96 41 [2] b2 4f [2] 99 63 [2] b7 41 [2] a3 5a [2] ac 40 [2] b2 5d [2] b0 5c [2] ab 5a [2] b7 5d [2] ab 72 }

  condition:
    any of them
}