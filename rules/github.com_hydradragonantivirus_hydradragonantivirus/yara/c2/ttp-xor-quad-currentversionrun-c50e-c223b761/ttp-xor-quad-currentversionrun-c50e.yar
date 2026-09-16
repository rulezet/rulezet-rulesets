rule TTP_XOR_QUAD_CurrentVersionRun_c50e {
  strings:
    $key_c50e = { 96 61 [2] b2 6f [2] 99 43 [2] b7 61 [2] a3 7a [2] ac 60 [2] b2 7d [2] b0 7c [2] ab 7a [2] b7 7d [2] ab 52 }

  condition:
    any of them
}