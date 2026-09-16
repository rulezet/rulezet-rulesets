rule TTP_XOR_QUAD_CurrentVersionRun_c2ff {
  strings:
    $key_c2ff = { 91 90 [2] b5 9e [2] 9e b2 [2] b0 90 [2] a4 8b [2] ab 91 [2] b5 8c [2] b7 8d [2] ac 8b [2] b0 8c [2] ac a3 }

  condition:
    any of them
}