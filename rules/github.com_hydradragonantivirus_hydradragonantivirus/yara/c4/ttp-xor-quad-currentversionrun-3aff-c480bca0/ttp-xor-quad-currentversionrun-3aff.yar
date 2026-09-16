rule TTP_XOR_QUAD_CurrentVersionRun_3aff {
  strings:
    $key_3aff = { 69 90 [2] 4d 9e [2] 66 b2 [2] 48 90 [2] 5c 8b [2] 53 91 [2] 4d 8c [2] 4f 8d [2] 54 8b [2] 48 8c [2] 54 a3 }

  condition:
    any of them
}