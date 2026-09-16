rule TTP_XOR_QUAD_CurrentVersionRun_aee7 {
  strings:
    $key_aee7 = { fd 88 [2] d9 86 [2] f2 aa [2] dc 88 [2] c8 93 [2] c7 89 [2] d9 94 [2] db 95 [2] c0 93 [2] dc 94 [2] c0 bb }

  condition:
    any of them
}