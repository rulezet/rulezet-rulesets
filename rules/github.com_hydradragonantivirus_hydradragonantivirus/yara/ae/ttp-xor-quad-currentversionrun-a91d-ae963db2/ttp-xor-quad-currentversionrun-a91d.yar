rule TTP_XOR_QUAD_CurrentVersionRun_a91d {
  strings:
    $key_a91d = { fa 72 [2] de 7c [2] f5 50 [2] db 72 [2] cf 69 [2] c0 73 [2] de 6e [2] dc 6f [2] c7 69 [2] db 6e [2] c7 41 }

  condition:
    any of them
}