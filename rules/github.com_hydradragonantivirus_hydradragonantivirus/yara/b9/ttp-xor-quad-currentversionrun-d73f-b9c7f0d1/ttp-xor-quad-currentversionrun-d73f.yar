rule TTP_XOR_QUAD_CurrentVersionRun_d73f {
  strings:
    $key_d73f = { 84 50 [2] a0 5e [2] 8b 72 [2] a5 50 [2] b1 4b [2] be 51 [2] a0 4c [2] a2 4d [2] b9 4b [2] a5 4c [2] b9 63 }

  condition:
    any of them
}