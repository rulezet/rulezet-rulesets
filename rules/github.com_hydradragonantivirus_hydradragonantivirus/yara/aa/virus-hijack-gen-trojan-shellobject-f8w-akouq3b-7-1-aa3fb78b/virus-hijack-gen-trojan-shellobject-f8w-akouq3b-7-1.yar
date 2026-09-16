rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd08078d36faa2fb481f9e5381f6c0c54e1374b4d16eee89acb5b4c1a3830eb"

  strings:
    $s1 = "ter version." fullword wide
    $s2 = "rogram is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN" wide
    $s3 = "You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Fo" wide
    $s4 = "This p" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}