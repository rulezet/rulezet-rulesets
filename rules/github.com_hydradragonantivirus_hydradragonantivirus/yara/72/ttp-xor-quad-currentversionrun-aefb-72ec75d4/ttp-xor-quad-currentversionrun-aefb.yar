rule TTP_XOR_QUAD_CurrentVersionRun_aefb {
  strings:
    $key_aefb = { fd 94 [2] d9 9a [2] f2 b6 [2] dc 94 [2] c8 8f [2] c7 95 [2] d9 88 [2] db 89 [2] c0 8f [2] dc 88 [2] c0 a7 }

  condition:
    any of them
}