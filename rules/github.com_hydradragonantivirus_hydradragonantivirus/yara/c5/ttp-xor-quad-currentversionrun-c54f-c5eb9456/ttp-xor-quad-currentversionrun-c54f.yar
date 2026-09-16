rule TTP_XOR_QUAD_CurrentVersionRun_c54f {
  strings:
    $key_c54f = { 96 20 [2] b2 2e [2] 99 02 [2] b7 20 [2] a3 3b [2] ac 21 [2] b2 3c [2] b0 3d [2] ab 3b [2] b7 3c [2] ab 13 }

  condition:
    any of them
}