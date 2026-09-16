rule TTP_XOR_QUAD_CurrentVersionRun_b04f {
  strings:
    $key_b04f = { e3 20 [2] c7 2e [2] ec 02 [2] c2 20 [2] d6 3b [2] d9 21 [2] c7 3c [2] c5 3d [2] de 3b [2] c2 3c [2] de 13 }

  condition:
    any of them
}