rule TTP_XOR_QUAD_CurrentVersionRun_aada {
  strings:
    $key_aada = { f9 b5 [2] dd bb [2] f6 97 [2] d8 b5 [2] cc ae [2] c3 b4 [2] dd a9 [2] df a8 [2] c4 ae [2] d8 a9 [2] c4 86 }

  condition:
    any of them
}