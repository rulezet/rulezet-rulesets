rule TTP_XOR_QUAD_CurrentVersionRun_d63f {
  strings:
    $key_d63f = { 85 50 [2] a1 5e [2] 8a 72 [2] a4 50 [2] b0 4b [2] bf 51 [2] a1 4c [2] a3 4d [2] b8 4b [2] a4 4c [2] b8 63 }

  condition:
    any of them
}