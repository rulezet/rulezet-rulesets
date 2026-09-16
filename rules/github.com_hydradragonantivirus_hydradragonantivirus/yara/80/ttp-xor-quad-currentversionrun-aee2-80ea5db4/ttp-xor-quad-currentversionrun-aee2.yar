rule TTP_XOR_QUAD_CurrentVersionRun_aee2 {
  strings:
    $key_aee2 = { fd 8d [2] d9 83 [2] f2 af [2] dc 8d [2] c8 96 [2] c7 8c [2] d9 91 [2] db 90 [2] c0 96 [2] dc 91 [2] c0 be }

  condition:
    any of them
}