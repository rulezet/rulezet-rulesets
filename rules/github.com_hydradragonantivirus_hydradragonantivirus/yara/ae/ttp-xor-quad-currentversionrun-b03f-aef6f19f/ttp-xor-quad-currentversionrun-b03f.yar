rule TTP_XOR_QUAD_CurrentVersionRun_b03f {
  strings:
    $key_b03f = { e3 50 [2] c7 5e [2] ec 72 [2] c2 50 [2] d6 4b [2] d9 51 [2] c7 4c [2] c5 4d [2] de 4b [2] c2 4c [2] de 63 }

  condition:
    any of them
}