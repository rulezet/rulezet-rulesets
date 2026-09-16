rule Sprawa_PL73092802_pdf {
	meta:
		description = "Auto-generated rule - file Sprawa_PL73092802.pdf.exe"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "7f0359314eb3577075367df11699cafd8a5f6c36da0e58890acebbce4144eb05"
	strings:
		$s1 = "blOGk_" fullword ascii 
		$s2 = "* lc~F" fullword ascii 
		$s3 = ".jwK[ " fullword ascii 
		$s4 = ".hvJ=R" fullword ascii 
		$s5 = "K}i*%S4" fullword ascii 
		$s6 = "1\"1'191C1H1d1n1" fullword ascii 
		$s7 = "2\"3.373=3C3J3Q3n3" fullword ascii 
		$s8 = "<l=+>,?<?M?U?e?v?" fullword ascii 
		$s9 = "=*=2=P=X=#?>?O?o?" fullword ascii 
		$s10 = "; ;$;(;,;0;4;l;t;|;" fullword ascii 
		$s11 = ">#>)>5>;>D>J>_>e>p>|>" fullword ascii 
		$s12 = "0)191?1K1Q1a1g1m1|1" fullword ascii 
		$s13 = "<;<A<O<T<\\<b<p<u<}<" fullword ascii 
		$s14 = "3&3/343:3D3M3X3d3i3y3~3" fullword ascii 
		$s15 = "4080<0@0D0H0L0P0T0X0" fullword ascii 
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and ( 10 of ($s*) ) ) or ( all of them )
}