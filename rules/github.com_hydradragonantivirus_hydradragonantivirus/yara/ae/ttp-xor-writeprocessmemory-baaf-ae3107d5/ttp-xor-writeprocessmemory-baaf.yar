rule TTP_XOR_WriteProcessMemory_baaf {
  strings:
    $key_baaf = { ed dd [2] df ff [2] d9 ca [2] f7 ca [2] c8 d6 }

  condition:
    any of them
}