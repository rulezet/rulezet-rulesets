rule TTP_XOR_QUAD_CurrentVersionRun_ae3c {
  strings:
    $key_ae3c = { fd 53 [2] d9 5d [2] f2 71 [2] dc 53 [2] c8 48 [2] c7 52 [2] d9 4f [2] db 4e [2] c0 48 [2] dc 4f [2] c0 60 }

  condition:
    any of them
}