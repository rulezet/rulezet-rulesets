rule TTP_XOR_QUAD_CurrentVersionRun_c50f {
  strings:
    $key_c50f = { 96 60 [2] b2 6e [2] 99 42 [2] b7 60 [2] a3 7b [2] ac 61 [2] b2 7c [2] b0 7d [2] ab 7b [2] b7 7c [2] ab 53 }

  condition:
    any of them
}