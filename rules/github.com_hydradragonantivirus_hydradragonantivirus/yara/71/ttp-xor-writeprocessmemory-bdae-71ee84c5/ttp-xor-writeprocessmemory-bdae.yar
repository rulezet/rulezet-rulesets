rule TTP_XOR_WriteProcessMemory_bdae {
  strings:
    $key_bdae = { ea dc [2] d8 fe [2] de cb [2] f0 cb [2] cf d7 }

  condition:
    any of them
}