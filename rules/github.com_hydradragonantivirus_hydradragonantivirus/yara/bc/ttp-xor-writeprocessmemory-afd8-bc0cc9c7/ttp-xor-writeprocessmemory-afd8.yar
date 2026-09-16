rule TTP_XOR_WriteProcessMemory_afd8 {
  strings:
    $key_afd8 = { f8 aa [2] ca 88 [2] cc bd [2] e2 bd [2] dd a1 }

  condition:
    any of them
}