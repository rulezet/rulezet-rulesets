rule TTP_XOR_WriteProcessMemory_adbe {
  strings:
    $key_adbe = { fa cc [2] c8 ee [2] ce db [2] e0 db [2] df c7 }

  condition:
    any of them
}