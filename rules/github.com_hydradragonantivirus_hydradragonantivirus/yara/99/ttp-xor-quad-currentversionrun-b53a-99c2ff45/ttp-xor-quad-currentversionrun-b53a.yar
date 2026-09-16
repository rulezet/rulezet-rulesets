rule TTP_XOR_QUAD_CurrentVersionRun_b53a {
  strings:
    $key_b53a = { e6 55 [2] c2 5b [2] e9 77 [2] c7 55 [2] d3 4e [2] dc 54 [2] c2 49 [2] c0 48 [2] db 4e [2] c7 49 [2] db 66 }

  condition:
    any of them
}