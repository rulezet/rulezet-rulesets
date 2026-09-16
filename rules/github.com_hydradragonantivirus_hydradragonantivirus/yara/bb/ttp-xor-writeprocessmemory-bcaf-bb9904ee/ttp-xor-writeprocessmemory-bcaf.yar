rule TTP_XOR_WriteProcessMemory_bcaf {
  strings:
    $key_bcaf = { eb dd [2] d9 ff [2] df ca [2] f1 ca [2] ce d6 }

  condition:
    any of them
}