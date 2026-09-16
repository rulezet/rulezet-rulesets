import "pe"
rule MASM {
  meta:
    author = "_pusher_"
    date   = "2016-08"
    linker = "5.12"
  
  condition:
    (pe.rich_signature.version(8078) and pe.rich_signature.version(8444) and pe.rich_signature.toolid(19))
    or      (pe.rich_signature.version(8078) and pe.rich_signature.version(30319) and pe.rich_signature.toolid(19))
    or      (pe.rich_signature.version(1735) and pe.rich_signature.version(8803) and pe.rich_signature.toolid(6))
    or
    (pe.rich_signature.version(1735) and pe.rich_signature.version(8444) and pe.rich_signature.toolid(6) and not pe.rich_signature.version(9782))

    or
    pe.rich_signature.version(1735) and pe.rich_signature.version(8447) and pe.rich_signature.toolid(6) and not ((pe.rich_signature.version(8168) and not pe.rich_signature.version(9782)))

    or      (pe.rich_signature.version(1735) and pe.rich_signature.version(8078) and pe.rich_signature.toolid(19))
    or
        (pe.rich_signature.version(8444) and pe.rich_signature.toolid(18) and not pe.rich_signature.version(30319) and not pe.rich_signature.version(9782))

        or
    (pe.rich_signature.version(7274) and pe.rich_signature.version(9049) and pe.rich_signature.toolid(19))
}